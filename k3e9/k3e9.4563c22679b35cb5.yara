
rule k3e9_4563c22679b35cb5
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4563c22679b35cb5"
     cluster="k3e9.4563c22679b35cb5"
     cluster_size="74"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['207b0a8a6906d7c9e67fdba3631c8ec6','21ff0fad34a40f62870e84e857f4cf8f','a7d37c0931204db41cc5defc87aa7e31']"

   strings:
      $hex_string = { 433b3b3d3f312d493a2b24543a2b26653d2f2d7d3c2f2b94392722a5443f41bc5b6d7ed8546ca2ea6188c7f66289c6f8638bc7f8494a5ae338251fc038292695 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
