
rule m3e9_411c9cc9cc000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.411c9cc9cc000b12"
     cluster="m3e9.411c9cc9cc000b12"
     cluster_size="391"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple rahack backdoor"
     md5_hashes="['011df5e87f1e760da7e0befd97e48985','017599f008e30cb64ecccc6b7795fcc2','19958ecb47b33c8ebf043a682ac81adb']"

   strings:
      $hex_string = { 494f36c822410fbafb33e8acd425c19ead179a90860973825ffb4b7438ed246611dffd58ead1d64ac3c3af3c9cb5882e75a761204e993a12278b1304007decf6 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
