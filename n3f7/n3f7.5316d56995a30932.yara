
rule n3f7_5316d56995a30932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f7.5316d56995a30932"
     cluster="n3f7.5316d56995a30932"
     cluster_size="34"
     filetype = "text/plain"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker autolike classic"
     md5_hashes="['00f6f54f7f4389a672c7e5f78014e51b','081d673d8b8c997c5598d86a1721e5dd','6a3b9cfcbb3a1f38d432727156e4f2f2']"

   strings:
      $hex_string = { 5d2f672c222022292e696e6465784f662861293e3d30293f637c7c642e707573682868293a63262628625b675d3d213129293b72657475726e21317d2c49443a }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
