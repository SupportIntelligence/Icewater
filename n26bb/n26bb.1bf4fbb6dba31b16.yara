
rule n26bb_1bf4fbb6dba31b16
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.1bf4fbb6dba31b16"
     cluster="n26bb.1bf4fbb6dba31b16"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="strictor injector malicious"
     md5_hashes="['1caaf03bb7508d120233612186fcd1c7d2abb620','07820fda25f1363368a38e2877990b8b98c39825','4ae6052a8fbd093b096fb35c0c6cf98addd882a9']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.1bf4fbb6dba31b16"

   strings:
      $hex_string = { eb0fe98095feffbb03010380e8de98feff8bc35f5e5b5dc2100090558bec83c4f85356578b5d148b750833c05568a2a0410064ff3064892085db7c0583fb027e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
