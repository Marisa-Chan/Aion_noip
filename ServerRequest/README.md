# Download patches and client
Download client

0. If needed - change CompanyID and gameID in requester script

1. Get Full client from 5th packet field "FullDownloadUrl"

2. For patches do request for "RepositoryServerAddress" and "GlobalVersion" from 3 and 6 packets

3. Make BaseUrl = http://{RepositoryServerAddress}/{GameID}/{GlobalVersion}/Patch/ 

4. Download filelist(UTF-16): {BaseUrl}/PatchFileInfo_{GameID}_{GlobalVersion}.dat 

5. Download needed files by using {BaseUrl} + filepaths from downloaded filelist.

**License** MIT
