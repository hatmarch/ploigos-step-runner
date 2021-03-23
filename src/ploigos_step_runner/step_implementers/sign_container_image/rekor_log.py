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
"""

import re
import sys
from io import StringIO
from pathlib import Path

import sh
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
    'container-image-signature-name',
    'rekor-server-url',
    'artifact-signature-file-path',
# curl-push
    'container-image-signature-server-password',
    'container-image-signature-server-url',
    'container-image-signature-server-username'
]

class RekorLog(StepImplementer):
    """`StepImplementer` for the `sign-container-image` step using Rekor to record the creation 
    of an artifact (image signature).
    """

    REKOR_LOG_ENTRY_OUTPUT_REGEX = re.compile(r"available at: *([^ ]+)\n$", re.MULTILINE)


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

    def _run_step(self):
        """Runs the step implemented by this StepImplementer.

        Returns
        -------
        StepResult
            Object containing the dictionary results of this step.
        """
        step_result = StepResult.from_step_implementer(self)

        # extract step results
        artifact_file_path = self.get_value('container-image-signature-file-path')
        container_signature_name = self.get_value('container-image-signature-name')
        private_key_fingerprint = self.get_value('container-image-signature-private-key-fingerprint')
        rekor_server_url = self.get_value('rekor-server-url')
        artifact_signature_path = Path(self.get_value('artifact-signature-file-path'))

        # extract configs
        signature_server_url = self.get_value(
            'container-image-signature-server-url'
        )
        signature_server_username = self.get_value(
            'container-image-signature-server-username'
        )
        signature_server_password = self.get_value(
            'container-image-signature-server-password'
        )

        try:
            RekorLog.__sign_artifact(
                artifact_file_path=artifact_file_path,
                private_key_fingerprint=private_key_fingerprint,
                signature_file_path=artifact_signature_path
            )
            log_url = RekorLog.__log_artifact( 
                artifact_file_path=artifact_file_path,
                rekor_server_url=rekor_server_url,
                private_key_fingerprint=private_key_fingerprint,
                signature_file_path=artifact_signature_path.absolute()
            )

            step_result.add_artifact(
                name='provenance-log-entry-url', value=log_url,
            )

            # get the previous signature name and replace the last part with our 
            # artifact signature to store it next to the container signature
            new_nexus_signature_name =  re.sub( 
                Path(container_signature_name).name,
                artifact_signature_path.name,
                container_signature_name)

            # # Add these artifacts to attempt to reuse CurlPush to nexus
            # step_result.add_artifact(
            #     name='container-image-signature-name', value=new_nexus_signature_name
            # )
            # step_result.add_artifact(
            #     name='container-image-signature-file-path', value=artifact_signature_path.absolute()
            # )

            artifact_signature_url = RekorLog.__store_artifact(
                    container_image_signature_file_path=artifact_signature_path.absolute(),
                    container_image_signature_name=new_nexus_signature_name,
                    signature_server_url=signature_server_url,
                    signature_server_username=signature_server_username,
                    signature_server_password = signature_server_password
                )
            
            step_result.add_artifact(
                name='artifact-signature-url', value=artifact_signature_url,
            )

        except StepRunnerException as error:
            step_result.success = False
            step_result.message = str(error)

        return step_result

    @staticmethod
    def __sign_artifact(  # pylint: disable=too-many-arguments
            artifact_file_path,
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
                '--detach-sig', artifact_file_path,
                _out=stdout_callback,
                _err_to_out=True,
                _tee='out'
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

    @staticmethod
    def __log_artifact(  # pylint: disable=too-many-arguments
            artifact_file_path,
            rekor_server_url,
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

            public_key_path = Path("public.pgp")

            # gpg will to to console if the public key exists already
            if (public_key_path.exists()):
                print(f"Removing existing public key at {public_key_path.absolute()}")
                public_key_path.unlink()

            print(f"Attempting to export public key for {private_key_fingerprint} to {public_key_path.absolute()}")
            sh.gpg(
                '--export',
                '--armor',
                '--output', public_key_path.absolute(),
                private_key_fingerprint,
                _out=stdout_callback,
                _err_to_out=True,
                _tee='out'
            )

            print(
                f"Public key for {private_key_fingerprint} exported to {public_key_path.absolute()}"
            )

            sh.rekor( 
                'upload',
                '--rekor_server', rekor_server_url,
                '--public-key', public_key_path.absolute(),
                '--signature',  signature_file_path,
                '--artifact',  artifact_file_path,
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
                    "Error getting rekor upload log entry."
                    "  See stdout and stderr for more info."
                )
            log_url = log_urls[0]

            print(
                "Logged signed artifact at "
                f"url='{log_url}'"
            )

        except sh.ErrorReturnCode as error:
            raise StepRunnerException(
                f"Error uploading to the rekor log: {error}"
            ) from error

        return log_url

    @staticmethod
    def __store_artifact(  # pylint: disable=too-many-arguments
        container_image_signature_file_path,
        container_image_signature_name,
        signature_server_url,
        signature_server_username,
        signature_server_password
    ):
        """Logs the artifact file path in rekor

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
