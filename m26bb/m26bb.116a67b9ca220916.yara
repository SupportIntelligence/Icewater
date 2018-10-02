
rule m26bb_116a67b9ca220916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m26bb.116a67b9ca220916"
     cluster="m26bb.116a67b9ca220916"
     cluster_size="85"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="installcore attribute ccmw"
     md5_hashes="['711840b7553b35cd78246bcc548142c8c9c05466','35d4e81dd91e8c6a29b3603fd13ddee1767ba55f','42b5203ceb1d9d6c87a3bec26270d552b5e22c06']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m26bb.116a67b9ca220916"

   strings:
      $hex_string = { cd374613420fd5906ddedb355dfe71be94e9862da0afe31e6ed089ee96b17f6a7ea49b5f4e2502a7840e10b4a3e17881ecc568ac72ed0382a27dc7670053766b }

   condition:
      
      filesize > 1048576 and filesize < 4194304
      and $hex_string
}
