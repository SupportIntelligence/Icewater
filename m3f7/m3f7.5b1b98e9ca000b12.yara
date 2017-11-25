
rule m3f7_5b1b98e9ca000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3f7.5b1b98e9ca000b12"
     cluster="m3f7.5b1b98e9ca000b12"
     cluster_size="3"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker script clicker"
     md5_hashes="['63b216e348a6e92b1b974f2afddc0ed0','6605b91da03254e1b7678a688db741df','eeda0773f21d82217b48b897ac1880e5']"

   strings:
      $hex_string = { 31466b556775515173443949546d443745435a494a5345344f5a6f3973746f566a432f7a63376b792b7a483968587756774470544157574c7267533351416538 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
