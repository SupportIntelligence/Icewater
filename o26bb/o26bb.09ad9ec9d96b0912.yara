
rule o26bb_09ad9ec9d96b0912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=o26bb.09ad9ec9d96b0912"
     cluster="o26bb.09ad9ec9d96b0912"
     cluster_size="28"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="razy malicious softcnapp"
     md5_hashes="['d1dcd0aaf184bf88b3aa3abc84f1d8f44d290247','be3d186ff69edab7b6449b0749ba5c73d4ffce25','4297c7f30243a2afde2d8f216ad45a6a363c4661']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=o26bb.09ad9ec9d96b0912"

   strings:
      $hex_string = { 3b5ddc1bc9234dd82b4ddc03cb8a0c11880c13438b55e442895dec837df0078955e41bf683e6fe83c60b8975f0e9350800002bf92bc18bcec1e9052bf1668933 }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
