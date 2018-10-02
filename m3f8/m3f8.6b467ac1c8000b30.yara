
rule m3f8_6b467ac1c8000b30
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f8.6b467ac1c8000b30"
     cluster="m3f8.6b467ac1c8000b30"
     cluster_size="7"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="androidos fakeinst fakeins"
     md5_hashes="['cc5796abb56ac9fc4a6010897ff87695541960fe','054660129ac2e0dd8e7d0e91a057e497f206e850','a19b0f7260be73804b8a5f82067f6efb055c1272']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=m3f8.6b467ac1c8000b30"

   strings:
      $hex_string = { 77436e31757630353942734c4745333352616a4d4e764f2f6f327a6a4151744b5046414964335458775342476b56445a6d37784d707869724f3538486b6d6e68 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
