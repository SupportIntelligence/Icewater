import "hash"

rule n3e9_610cee7ce22ed132
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.610cee7ce22ed132"
     cluster="n3e9.610cee7ce22ed132"
     cluster_size="12050 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="virut virtob virux"
     md5_hashes="['0e7d0345bd710aac37f18c4cf14a3f83', '01b8b36c6d10611ce6488b6d312c021e', '02b96462873b8b4fd1a6d43f37084a29']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(294912,1024) == "e9980409bd58ef812d6b8d5d6eaa1014"
}

