import "hash"

rule o3ed_635244cece529b12
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=o3ed.635244cece529b12"
     cluster="o3ed.635244cece529b12"
     cluster_size="23 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['9bf1f369e52f777204d5348542b89c01', '84db59cb350331647cfc4485d877f99c', '84db59cb350331647cfc4485d877f99c']"


   condition:
      filesize > 1048576 and filesize < 4194304
      and hash.md5(2779136,1024) == "9e9ec715484cb1af8b99faa9662b062c"
}

