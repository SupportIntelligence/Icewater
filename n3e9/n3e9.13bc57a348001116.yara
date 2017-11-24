
rule n3e9_13bc57a348001116
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.13bc57a348001116"
     cluster="n3e9.13bc57a348001116"
     cluster_size="16"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="pykspa autorun blocker"
     md5_hashes="['6a1d31ef4428965adcef4e3f31cc6f3c','7fba3de2eb2a0bc137d882085f39ad5d','ff0fe4268e6c9d07933161c444186c76']"

   strings:
      $hex_string = { 097e8ca4572a9e9d737fbadc4c25a85610e5c589343c70e84a272066c06f13113e5149ee21546dd1b77dc097f8dee1aabb8588dba2ed74ddf96e2e52b8c9b2e3 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
