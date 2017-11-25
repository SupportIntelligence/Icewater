
rule n3e9_13a9292f86221116
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.13a9292f86221116"
     cluster="n3e9.13a9292f86221116"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="pykspa agentwdcr autorun"
     md5_hashes="['5d2357d2d94e8f5fa025fe072cbf8de2','6e9481401db3507a4697fed377cf4ec7','cdcaee5d8aa305977b58b389b17a5e1a']"

   strings:
      $hex_string = { 097e8ca4572a9e9d737fbadc4c25a85610e5c589343c70e84a272066c06f13113e5149ee21546dd1b77dc097f8dee1aabb8588dba2ed74ddf96e2e52b8c9b2e3 }

   condition:
      
      filesize > 4194304 and filesize < 16777216
      and $hex_string
}
