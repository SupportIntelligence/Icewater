import "hash"

rule n3ed_51996b66d9eb1932
{

   meta:
     copyright="Copyright (c) 2014-2017 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.2.2 divinorum/0.99 icewater/0.3.01"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.51996b66d9eb1932"
     cluster="n3ed.51996b66d9eb1932"
     cluster_size="54 samples"
     filetype = "pe"
     tlp = "amber"
     version = "icewater foxtail"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171009"
     license = "RIL v1.0 see https://raw.githubusercontent.com/SupportIntelligence/Icewater/master/LICENSE"
     family="ramnit nimnul bmnup"
     md5_hashes="['c9481787fb143f1cec2cc922a538a985', 'cdbcb6079dadd3809f57dbd3aa014b9f', 'c0e9fa00809d238f8a88dffdafd75d29']"


   condition:
      filesize > 262144 and filesize < 1048576
      and hash.md5(452608,1024) == "0ddef2dd9490e351383cfa60e754d5ae"
}

