
rule n26bb_1b704b3b95eb1916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.1b704b3b95eb1916"
     cluster="n26bb.1b704b3b95eb1916"
     cluster_size="5"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="fareit injector backdoor"
     md5_hashes="['08e411482c87a2a8b92a5e4536bda8fc779557c7','016caf776552485d95327caf76bf2bb6b6723232','bd56fd6bf52ee7b61a83d09c231c43133369ce49']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.1b704b3b95eb1916"

   strings:
      $hex_string = { eb0fe9a083feffbb03010380e8fe86feff8bc35f5e5b5dc2100090558bec83c4f85356578b5d148b750833c0556892b2410064ff3064892085db7c0583fb027e }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
