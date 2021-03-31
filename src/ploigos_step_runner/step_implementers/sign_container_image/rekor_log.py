"""`StepImplementer` for the `sign-container-image` step using Rekor to record the creation of an artifact (image signature).

Step Configuration
------------------
Step configuration expected as input to this step.
Could come from:

  * static configuration
  * runtime configuration
  * previous step results

Configuration Key                           | Required? | Default | Description
--------------------------------------------|-----------|---------|-------------
`container-image-signature-file-path`       | Yes       |         | Local file path to container \
                                                                    image signature to push.
`container-image-signature-name`            | Yes       |         | Fully qualified name of the \
                                                                    name of the image signature, \
                                                                    including: organization, repo, \
                                                                    and hash. <br/>\
                                                                    ex: user/hello-node@sha256=\
                                                                    2cbdb73c9177e63e85d267f738e9\
                                                                    9e368db3f806eab4c541f5c6b719\
                                                                    e69f1a2b/signature-1

Result Artifacts
----------------
Results artifacts output by this step.

Result Artifact Key                   | Description
--------------------------------------|------------
`artifact-log-url`                    | the URL of the Rekor log entry for this artifact
`artifact-signature-url`              | the URL where the sig can be found for the artifact
"""

import os
import re
import sys
from io import StringIO
from pathlib import Path

import sh
import base64
import json
import hashlib
from ploigos_step_runner import StepImplementer
from ploigos_step_runner.exceptions import StepRunnerException
from ploigos_step_runner.step_result import StepResult
from ploigos_step_runner.utils.io import create_sh_redirect_to_multiple_streams_fn_callback

# testing
DEFAULT_CONFIG = {
    # 'container-image-signature-file-path': "/workspaces/tssc-demo/secrets/OWNERS.md",
    # 'rekor-server-url': 'http://rekor-server-tssc-demo-rekor.apps.cluster-3627.3627.example.opentlc.com',
    # 'container-image-signer-pgp-public-key': "/workspaces/tssc-demo/secrets/gpg_public_key",
    # 'container-image-signature-private-key-fingerprint': "97901C34A0026E2F2F9E40F992418AD1F23FDF56",
    # 'artifact-signature-file-path': "/workspaces/tssc-demo/secrets/artifact-sig.asc"
}


REQUIRED_CONFIG_OR_PREVIOUS_STEP_RESULT_ARTIFACT_KEYS = [
    'container-image-signature-file-path',
    'container-image-signature-private-key-fingerprint',
    # 'container-image-signature-name',
    'rekor-server-url',
    # 'artifact-signature-file-path',
# curl-push
    # 'container-image-signature-server-password',
    # 'container-image-signature-server-url',
    # 'container-image-signature-server-username'
]

class RekorLog(StepImplementer):
    """`StepImplementer` for the `sign-container-image` step using Rekor to record the creation 
    of an artifact (image signature).
    """

    # See also: https://bit.ly/3rD5Acg
    REKOR_LOG_ENTRY_OUTPUT_REGEX = re.compile(r"available at: *([^ ]+/([^ ]+))\n", re.MULTILINE)

    @staticmethod
    def step_implementer_config_defaults():
        """Getter for the StepImplementer's configuration defaults.

        Returns
        -------
        dict
            Default values to use for step configuration values.

        Notes
        -----
        These are the lowest precedence configuration values.
        """
        return DEFAULT_CONFIG

    @staticmethod
    def _required_config_or_result_keys():
        """Getter for step configuration or previous step result artifacts that are required before
        running this step.

        See Also
        --------
        _validate_required_config_or_previous_step_result_artifact_keys

        Returns
        -------
        array_list
            Array of configuration keys or previous step result artifacts
            that are required before running the step.
        """
        return REQUIRED_CONFIG_OR_PREVIOUS_STEP_RESULT_ARTIFACT_KEYS

    @property
    def rekor_server_url(self):
        """
        Returns
        -------
        RekorServerUrl
            The URL of the rekor server
        """
   
    @staticmethod
    def base64_encode(
        file_path
    ):
        """Given a file_path, read and encode the contents in base64

        Returns
        -------
        Base64Contents
            base64 encoded string of file contents
        """
        return base64.b64encode(Path(file_path).read_text().encode('ascii')).decode('ascii')

    def __export_public_key(self, 
        private_key_fingerprint
    ):
        try:
            stdout_result = StringIO()
            stdout_callback = create_sh_redirect_to_multiple_streams_fn_callback([
                sys.stdout,
                stdout_result
            ])

            # Make sure there is no file at the public key path or the gpg will go
            # interactive to ask us if we want to overwrite it
            public_key_path = Path(os.path.join(self.work_dir_path_step, 'signature.pub'))
            if public_key_path.exists():
                public_key_path.unlink()

            print(f"Attempting to export public key for {private_key_fingerprint} to {public_key_path}")
            sh.gpg(
                '--export',
                '--armor',
                '--output', public_key_path,
                private_key_fingerprint,
                _out=stdout_callback,
                _err_to_out=True,
                _tee='out'
            )

            print(
                f"Public key for {private_key_fingerprint} exported to {public_key_path}"
            )  
        
        except sh.ErrorReturnCode as error:
            raise StepRunnerException(
                f"Error signing artifact with gpg: {error}"
            ) from error
        
        return public_key_path
              

    def _run_step(self):
        """Runs the step implemented by this StepImplementer.

        Returns
        -------
        StepResult
            Object containing the dictionary results of this step.
        """
        step_result = StepResult.from_step_implementer(self)

        # extract step results
        signature_file_path = self.get_value('container-image-signature-file-path')
        private_key_fingerprint = self.get_value('container-image-signature-private-key-fingerprint')
        self.__rekor_server_url=self.get_value('rekor-server-url')

        try:
            # only run conditionally based on environment

            print("Signing artifact YML and storing in rekor")
            build_artifact_path = Path(self.results_file_path)
            rekor_log_entry_uuid, rekor_log_entry_url = self.sign_and_store_artifact(
                previous_log_entry_uuid=0,   
                artifact_file_path=build_artifact_path,
                private_key_fingerprint=private_key_fingerprint
            )

            print(f"Binding the container signature to the build output artifacts at {rekor_log_entry_uuid}")
            final_rekor_log_entry_uuid, final_rekor_log_entry_url = self.sign_and_store_artifact(
                previous_log_entry_uuid=rekor_log_entry_uuid,
                artifact_file_path=Path(signature_file_path),
                private_key_fingerprint=private_key_fingerprint
            )

            # FIXME: Tag the image digest with the uuid

            step_result.add_artifact(
                name='final-log-entry-url', value=final_rekor_log_entry_url,
            )

            step_result.add_artifact(
                name='final-log-entry-uuid', value=final_rekor_log_entry_uuid,
            )

        except StepRunnerException as error:
            step_result.success = False
            step_result.message = str(error)

        return step_result

    def sign_and_store_artifact( self, # pylint: disable=too-many-arguments
        previous_log_entry_uuid,
        artifact_file_path,
        private_key_fingerprint
    ):
        """Signs artifact at artifact_file_path with key at private_key_fingerprint and stores in Rekor

        Notes
        -----
        Assumes that key for private_key_fingerprint has already been imported

        Returns
        -------
        uuid
            The uuid of the rekor log entry for this artifact
        url
            The url of the rekor log entry

        Raises
        ------
        StepRunnerException
            If error signing artifact or storing in Rekor
        """

        # Create a build output node around the artifact which we can store in Rekor
        build_output_node = self.__create_build_output_node(
            artifact_file_path=artifact_file_path,
            previous_rekor_entry_uuid=previous_log_entry_uuid
        )

        # Specify where we want signature file to go
        signature_file_path = Path(os.path.join(self.work_dir_path_step, 'node-sig.asc'))
        RekorLog.__sign_artifact_contents(
            artifact_contents=json.dumps(build_output_node),
            private_key_fingerprint=private_key_fingerprint,
            signature_file_path=signature_file_path
        )

        rekor_entry_uuid, rekor_entry_url = self.__log_build_output_node(  # pylint: disable=too-many-arguments
            build_output_node=build_output_node,
            private_key_fingerprint=private_key_fingerprint,
            signature_file_path=signature_file_path
        )

        return rekor_entry_uuid, rekor_entry_url

    @staticmethod
    def __sign_artifact_contents(  # pylint: disable=too-many-arguments
            artifact_contents,
            private_key_fingerprint,
            signature_file_path,
    ):
        """Signs the artifact

        Raises
        ------
        StepRunnerException
            If error pushing image signature.
        """

        try:
            stdout_result = StringIO()
            stdout_callback = create_sh_redirect_to_multiple_streams_fn_callback([
                sys.stdout,
                stdout_result
            ])

            sig_file=Path(signature_file_path)
            if sig_file.exists():
                sig_file.unlink()

            sh.gpg( 
                '--armor',
                '-u', private_key_fingerprint,
                '--output', signature_file_path,
                '--detach-sig',
                _out=stdout_callback,
                _err_to_out=True,
                _tee='out',
                _in=artifact_contents
            )

            sig_file=Path(signature_file_path)
            if not sig_file.is_file():
                raise StepRunnerException(
                    f"No artifact signature file was created at: {signature_file_path}"
                ) 
 
        except sh.ErrorReturnCode as error:
            raise StepRunnerException(
                f"Error signing artifact with gpg: {error}"
            ) from error

    def __create_build_output_node( # pylint: disable=too-many-arguments
        self,
        artifact_file_path,
        previous_rekor_entry_uuid
    ):
        """Creates a build output node that is to be stored in the Rekor immutable database

        Returns
        -------
        BuildOutputNodePath
            Path to the node file (to be signed and then stored in Rekor log)
        """

        # Get the output artifact as base64 encoded
        if (not artifact_file_path.exists() or not artifact_file_path.is_file()):
            raise StepRunnerException(
                f"Cannot open {artifact_file_path.absolute()}"
            )

        build_node_data = {
            "stepName": self.step_name,
            "stepOutput": self.base64_encode(artifact_file_path),
            "previousRekorUUID": previous_rekor_entry_uuid
        }

        return build_node_data

    def __log_build_output_node(  self, # pylint: disable=too-many-arguments
            build_output_node,
            private_key_fingerprint,
            signature_file_path
    ):
        """Logs the artifact file path in rekor

        Raises
        ------
        StepRunnerException
            If error pushing image signature.
        """

        try:
            stdout_result = StringIO()
            stdout_callback = create_sh_redirect_to_multiple_streams_fn_callback([
                sys.stdout,
                stdout_result
            ])

            public_key_path = self.__export_public_key(private_key_fingerprint)

            artifact_file_path=Path(os.path.join(self.work_dir_path, 'node.json'))
            if artifact_file_path.exists():
                artifact_file_path.unlink()
            artifact_file_path.write_text(json.dumps(build_output_node))


            rekor_entry = RekorLog.__create_rekor_entry(
                artifact_file_path,
                public_key_path,
                signature_file_path,
            )

            # need to write the rekor entry to disk before we can upload it
            rekor_entry_path = Path(os.path.join(self.work_dir_path,'entry.json'))
            if rekor_entry_path.exists():
                rekor_entry_path.unlink()
            rekor_entry_path.write_text(json.dumps(rekor_entry))

            sh.rekor( 
                'upload',
                '--rekor_server', self.__rekor_server_url,
                '--entry', rekor_entry_path.absolute(),
                _out=stdout_callback,
                _err_to_out=True,
                _tee='out'
            )

            # Output looks like this:
            # Created entry at index 0, available at: 
            # http://rekor-server-tssc-demo-rekor.apps.cluster-3627.3627.example.opentlc.com/api/v1/log/entries/1b64ae04c29363f8f6fa9731a0d1d47dedb0b97fd9b49e7e333b2e54cea060ff
            log_urls = re.findall(
                RekorLog.REKOR_LOG_ENTRY_OUTPUT_REGEX,
                stdout_result.getvalue()
            )

            if len(log_urls) < 1:
                raise StepRunnerException(
                    "Error getting rekor upload log url"
                    "  See stdout and stderr for more info."
                )

            if len(log_urls[0]) < 2:
                raise StepRunnerException(
                    "Error getting rekor upload log entry uuid"
                    "  See stdout and stderr for more info."
            )
            log_entry_url = log_urls[0][0]
            log_entry_uuid = log_urls[0][1]

            print(
                "Logged signed artifact at "
                f"url='{log_entry_url}' uuid='{log_entry_uuid}'"
            )

        except sh.ErrorReturnCode as error:
            raise StepRunnerException(
                f"Error uploading to the rekor log: {error}"
            ) from error

        return log_entry_uuid, log_entry_url

    @staticmethod
    def __create_rekor_entry(  # pylint: disable=too-many-arguments
        artifact_file_path,
        public_key_path,
        signature_file_path,
    ):
        artifact_hash = hashlib.sha256(artifact_file_path.read_bytes()).hexdigest()
        # print(f"Hash is {artifact_hash}")
        base64_encoded_artifact = RekorLog.base64_encode(artifact_file_path)

        rekor_entry = {
            "kind": "rekord",
            "apiVersion": "0.0.1",
            "spec": {
                "signature": {
                    "format": "pgp",
                    "content": RekorLog.base64_encode(signature_file_path),
                    "publicKey": {
                        "content": RekorLog.base64_encode(public_key_path)
                    }
                },
                "data": {
                    "content": base64_encoded_artifact,
                    "hash": {
                        "algorithm": "sha256",
                        "value": artifact_hash
                    }
                },
                "extraData": base64_encoded_artifact
            }
        }

        return rekor_entry;


    @staticmethod
    def __store_artifact(  # pylint: disable=too-many-arguments
        container_image_signature_file_path,
        container_image_signature_name,
        signature_server_url,
        signature_server_username,
        signature_server_password
    ):
        """Stores an artifact in nexus

        Raises
        ------
        StepRunnerException
            If error pushing image signature.
        """
        # remove any trailing / from url
        signature_server_url = re.sub(r'/$', '', signature_server_url)
        container_image_signature_url = f"{signature_server_url}/{container_image_signature_name}"

        try:
            stdout_result = StringIO()
            stdout_callback = create_sh_redirect_to_multiple_streams_fn_callback([
                sys.stdout,
                stdout_result
            ])

            # -s: Silent
            # -S: Show error
            # -f: Don't print out failure document
            # -v: Verbose
            sh.curl(  # pylint: disable=no-member
                '-sSfv',
                '-X', 'PUT',
                '--user', f"{signature_server_username}:{signature_server_password}",
                '--upload-file', container_image_signature_file_path,
                container_image_signature_url,
                _out=stdout_callback,
                _err_to_out=True,
                _tee='out'
            )
        except sh.ErrorReturnCode as error:
            raise StepRunnerException(
                f"Error pushing signature file to signature server using curl: {error}"
            ) from error

        return container_image_signature_url
