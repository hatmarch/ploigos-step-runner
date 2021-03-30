# pylint: disable=missing-module-docstring
# pylint: disable=missing-class-docstring
# pylint: disable=missing-function-docstring
import os
import re
import sys
from io import IOBase
from io import StringIO
from unittest.mock import patch

import sh
import json
import base64
from pathlib import Path
from testfixtures import TempDirectory
from tests.helpers.base_step_implementer_test_case import \
    BaseStepImplementerTestCase
from tests.helpers.test_utils import Any, StringRegexParam
from ploigos_step_runner.step_implementers.sign_container_image import RekorLog
from ploigos_step_runner.step_result import StepResult
from ploigos_step_runner.utils.io import create_sh_redirect_to_multiple_streams_fn_callback


class TestStepImplementerRekorLogSourceBase(BaseStepImplementerTestCase):

    TESTS_GPG_KEY_FINGERPRINT = '6F70E1656E932EFEE8AD898A98871DAE82786C09'

    def setUp(self):
        super().setUp()

        self.install_gpg_key()

    def tearDown(self):
        super().tearDown()

        self.delete_gpg_key()

    def install_gpg_key(self):
        # install private key
        gpg_private_key_path = os.path.join(
            os.path.dirname(__file__),
            '../../helpers/files',
            'ploigos-step-runner-tests-private.asc'
        )
        sh.gpg( # pylint: disable=no-member
            '--import',
            gpg_private_key_path
        )

    def delete_gpg_key(self):
        try:
            # uninstall private key
            sh.gpg( # pylint: disable=no-member
                '--batch',
                '--pinentry-mode',
                'loopback',
                '--yes',
                '--delete-secret-keys',
                self.TESTS_GPG_KEY_FINGERPRINT
            )
        except:
            # don't care if this fails really
            # could fail cuz the test uninstalled it already
            pass

    def create_step_implementer(
            self,
            step_config={},
            step_name='',
            implementer='',
            results_dir_path='',
            results_file_name='',
            work_dir_path=''
    ):
        return self.create_given_step_implementer(
            step_implementer=RekorLog,
            step_config=step_config,
            step_name=step_name,
            implementer=implementer,
            results_dir_path=results_dir_path,
            results_file_name=results_file_name,
            work_dir_path=work_dir_path
        )

    # TESTS FOR configuration checks
    def test_step_implementer_config_defaults(self):
        defaults = RekorLog.step_implementer_config_defaults()
        expected_defaults = {}
        self.assertEqual(defaults, expected_defaults)

    def test__required_config_or_result_keys(self):
        required_keys = RekorLog._required_config_or_result_keys()
        expected_required_keys = [
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
        self.assertEqual(required_keys, expected_required_keys)
    
    def test__create_build_output_node(self):
        example_output_file_path = os.path.join(
            os.path.dirname(__file__),
            '../../files',
            'example-step-runner-results.yml'
            )

        step_name = 'test-rekor-log'
        previous_rekor_entry_uuid = '1234-56789'
        
        buildNodeContent = RekorLog.create_build_output_node(
            step_name = step_name,
            output_artifact_path = example_output_file_path,
            previous_rekor_entry_uuid = previous_rekor_entry_uuid
        )

        buildNodeObj = json.loads(buildNodeContent)

        outputFileText = Path(example_output_file_path).read_text()
        stepOutputText = base64.b64decode(buildNodeObj['stepOutput'].encode('ascii')).decode('ascii')

        self.assertEqual(outputFileText, stepOutputText)
        self.assertEqual(buildNodeObj['stepName'], step_name)
        self.assertEqual(buildNodeObj['previousRekorUUID'], previous_rekor_entry_uuid)

        return buildNodeObj

    def test__sign_build_output_node(self):
        with TempDirectory() as temp_dir:
            local_signature_file_path = os.path.join(temp_dir.path, 'node-sig.asc')
    
            buildNodeObj = self.test__create_build_output_node()

            RekorLog.sign_build_output_node(
                build_output_node=buildNodeObj,
                private_key_fingerprint=self.TESTS_GPG_KEY_FINGERPRINT, 
                signature_file_path=local_signature_file_path
            )

            decrypted_output = self.__decrypt_sig(
                signature_file_path=local_signature_file_path,
                private_key_fingerprint=self.TESTS_GPG_KEY_FINGERPRINT              
            )
            expected_output=json.dumps(buildNodeObj)

            self.assertEqual(decrypted_output, expected_output)

    def __decrypt_sig(
        self,
        signature_file_path,
        private_key_fingerprint
    ):
        # GPG_OUTPUT_REGEX = re.compile(r"using RSA key ([A-Za-z0-9]+).*(Good signature)", re.DOTALL)
        GPG_OUTPUT_REGEX = re.compile(f"using RSA key {private_key_fingerprint}.*Good signature", re.DOTALL)

        with TempDirectory() as temp_dir:
            signature_file_path=Path(signature_file_path)

            output_path=os.path.join(temp_dir.path,'output.json')

            try:
                stdout_result = StringIO()
                stdout_callback = create_sh_redirect_to_multiple_streams_fn_callback([
                    sys.stdout,
                    stdout_result
                ])

                sh.gpg( 
                    '--output', output_path,
                    '--decrypt', signature_file_path,
                    _out=stdout_callback,
                    _err_to_out=True,
                    _tee='out'
                )

                verify_matches = re.findall(
                    GPG_OUTPUT_REGEX,
                    stdout_result.getvalue()
                )

                if len(verify_matches) < 1:
                    raise Exception (
                       f"Bad signature or not signed by {private_key_fingerprint}"
                    )
                
                return Path(output_path).read_text()
    
            except sh.ErrorReturnCode as error:
                raise Exception(
                    f"Error verifying sig with gpg: {error}"
                ) from error


    # @patch('sh.curl', create=True)
    # def test_run_step_pass(self, curl_mock):
    #     with TempDirectory() as temp_dir:
    #         results_dir_path = os.path.join(temp_dir.path, 'step-runner-results')
    #         results_file_name = 'step-runner-results.yml'
    #         work_dir_path = os.path.join(temp_dir.path, 'working')
    #         signature_file_path = 'signature-1'
    #         temp_dir.write(signature_file_path, b'bogus signature')
    #         container_image_signature_file_path = os.path.join(temp_dir.path, signature_file_path)

    #         container_image_signature_name = 'jkeam/hello-node@sha256=2cbdb73c9177e63e85d267f738e' \
    #             '99e368db3f806eab4c541f5c6b719e69f1a2b/signature-1'

    #         step_config = {
    #             'container-image-signature-server-url': 'https://sigserver/signatures',
    #             'container-image-signature-server-username': 'admin',
    #             'container-image-signature-server-password': 'adminPassword',
    #             'with-fips': True
    #         }

    #         # Previous (fake) results
    #         artifact_config = {
    #             'container-image-signature-file-path': {'value': container_image_signature_file_path},
    #             'container-image-signature-name': {'value': container_image_signature_name},
    #         }
    #         self.setup_previous_result(work_dir_path, artifact_config)

    #         # Actual results
    #         step_implementer = self.create_step_implementer(
    #             step_config=step_config,
    #             step_name='sign-container-image',
    #             implementer='CurlPush',
    #             results_dir_path=results_dir_path,
    #             results_file_name=results_file_name,
    #             work_dir_path=work_dir_path,
    #         )

    #         result = step_implementer._run_step()

    #         # Expected results
    #         expected_step_result = StepResult(step_name='sign-container-image', sub_step_name='CurlPush',
    #                                           sub_step_implementer_name='CurlPush')
    #         expected_step_result.add_artifact(name='container-image-signature-url', value=f'https://sigserver/signatures/{container_image_signature_name}')

    #         self.assertEqual(expected_step_result.get_step_result_dict(), result.get_step_result_dict())
    #         curl_mock.assert_called_once_with(
    #             '-sSfv',
    #             '-X', 'PUT',
    #             '--user', "admin:adminPassword",
    #             '--upload-file', container_image_signature_file_path,
    #             f"https://sigserver/signatures/{container_image_signature_name}",
    #             _out=Any(IOBase),
    #             _err_to_out=True,
    #             _tee='out'
    #         )

    # @patch('sh.curl', create=True)
    # def test_run_step_pass_nofips(self, curl_mock):
    #     with TempDirectory() as temp_dir:
    #         results_dir_path = os.path.join(temp_dir.path, 'step-runner-results')
    #         results_file_name = 'step-runner-results.yml'
    #         work_dir_path = os.path.join(temp_dir.path, 'working')
    #         signature_file_path = 'signature-1'
    #         temp_dir.write(signature_file_path, b'bogus signature')
    #         container_image_signature_file_path = os.path.join(temp_dir.path, signature_file_path)

    #         container_image_signature_name = 'jkeam/hello-node@sha256=2cbdb73c9177e63e85d267f738e' \
    #             '99e368db3f806eab4c541f5c6b719e69f1a2b/signature-1'

    #         step_config = {
    #             'container-image-signature-server-url': 'https://sigserver/signatures',
    #             'container-image-signature-server-username': 'admin',
    #             'container-image-signature-server-password': 'adminPassword',
    #             'with-fips': False
    #         }

    #         # Previous (fake) results
    #         artifact_config = {
    #             'container-image-signature-file-path': {'value': container_image_signature_file_path},
    #             'container-image-signature-name': {'value': container_image_signature_name},
    #         }
    #         self.setup_previous_result(work_dir_path, artifact_config)

    #         # Actual results
    #         step_implementer = self.create_step_implementer(
    #             step_config=step_config,
    #             step_name='sign-container-image',
    #             implementer='CurlPush',
    #             results_dir_path=results_dir_path,
    #             results_file_name=results_file_name,
    #             work_dir_path=work_dir_path,
    #         )

    #         result = step_implementer._run_step()

    #         # # Expected results
    #         expected_step_result = StepResult(step_name='sign-container-image', sub_step_name='CurlPush',
    #                                           sub_step_implementer_name='CurlPush')
    #         expected_step_result.add_artifact(name='container-image-signature-url', value=f'https://sigserver/signatures/{container_image_signature_name}')
    #         expected_step_result.add_artifact(name='container-image-signature-file-sha1', value='d9ba1fc747829392883c48adfe4bb688239dc8b2')
    #         expected_step_result.add_artifact(name='container-image-signature-file-md5', value='b66c5c3d4ab37a50e69a05d72ba302fa')

    #         self.assertEqual(expected_step_result.get_step_result_dict(), result.get_step_result_dict())
    #         curl_mock.assert_called_once_with(
    #             '-sSfv',
    #             '-X', 'PUT',
    #             '--user', "admin:adminPassword",
    #             '--upload-file', container_image_signature_file_path,
    #             '--header', StringRegexParam(r'X-Checksum-Sha1:.+'),
    #             '--header', StringRegexParam(r'X-Checksum-MD5:.+'),
    #             f"https://sigserver/signatures/{container_image_signature_name}",
    #             _out=Any(IOBase),
    #             _err_to_out=True,
    #             _tee='out'
    #         )

    # @patch('sh.curl', create=True)
    # def test_run_step_fail(self, curl_mock):
    #     with TempDirectory() as temp_dir:
    #         results_dir_path = os.path.join(temp_dir.path, 'step-runner-results')
    #         results_file_name = 'step-runner-results.yml'
    #         work_dir_path = os.path.join(temp_dir.path, 'working')
    #         signature_file_path = 'signature-1'
    #         temp_dir.write(signature_file_path, b'bogus signature')
    #         container_image_signature_file_path = os.path.join(temp_dir.path, signature_file_path)

    #         container_image_signature_name = 'jkeam/hello-node@sha256=2cbdb73c9177e63e85d267f738e' \
    #             '99e368db3f806eab4c541f5c6b719e69f1a2b/signature-1'

    #         step_config = {
    #             'container-image-signature-server-url': 'https://sigserver/signatures',
    #             'container-image-signature-server-username': 'admin',
    #             'container-image-signature-server-password': 'adminPassword'
    #         }

    #         # Previous (fake) results
    #         artifact_config = {
    #             'container-image-signature-file-path': {'value': container_image_signature_file_path},
    #             'container-image-signature-name': {'value': container_image_signature_name},
    #         }
    #         self.setup_previous_result(work_dir_path, artifact_config)

    #         # Actual results
    #         step_implementer = self.create_step_implementer(
    #             step_config=step_config,
    #             step_name='sign-container-image',
    #             implementer='CurlPush',
    #             results_dir_path=results_dir_path,
    #             results_file_name=results_file_name,
    #             work_dir_path=work_dir_path,
    #         )
    #         sh.curl.side_effect = sh.ErrorReturnCode('curl', b'mock stdout', b'mock error')

    #         result = step_implementer._run_step()

    #         # # Expected results
    #         expected_step_result = StepResult(
    #             step_name='sign-container-image',
    #             sub_step_name='CurlPush',
    #             sub_step_implementer_name='CurlPush'
    #         )
    #         expected_step_result.success = False
    #         expected_step_result.message = "foo"

    #         self.assertEqual(result.success, expected_step_result.success)
    #         self.assertEqual(result.artifacts, expected_step_result.artifacts)
    #         self.assertRegex(
    #             result.message,
    #             re.compile(
    #                 r"Error pushing signature file to signature server using curl: "
    #                 r".*RAN: curl"
    #                 r".*STDOUT:"
    #                 r".*mock stdout"
    #                 r".*STDERR:"
    #                 r".*mock error",
    #                 re.DOTALL
    #             )
    #         )
    #         curl_mock.assert_called_once_with(
    #             '-sSfv',
    #             '-X', 'PUT',
    #             '--user', "admin:adminPassword",
    #             '--upload-file', container_image_signature_file_path,
    #             f"https://sigserver/signatures/{container_image_signature_name}",
    #             _out=Any(IOBase),
    #             _err_to_out=True,
    #             _tee='out'
    #         )
