
rule m26bb_3469122bc946b94e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.3469122bc946b94e"
     cluster="m26bb.3469122bc946b94e"
     cluster_size="19"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="virtob virut malicious"
     md5_hashes="['0d65b689aca4bc52719ede751e3833dae2d5ec3c','1c0d9ed8970a968df00e96052d718e4990a17bbf','7e8fa5a53f8ce9760568912b186fe15fc3e48f36']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.3469122bc946b94e"

   strings:
      $hex_string = { 000000f4fa7c1b3f713c47bbcd6137425faeaf03000000aaa5e4196256c54fa0c01758028e1057010000001400000024c3dd6f034efe4bb1853d77768dc90c16 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
