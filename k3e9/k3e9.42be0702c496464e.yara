
rule k3e9_42be0702c496464e
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.42be0702c496464e"
     cluster="k3e9.42be0702c496464e"
     cluster_size="423"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['003e233c5d2d3e7d5021eb3878f596ab','0257dc49e01e9addad02b60772c8cd79','09c29793ca206c6dd72f4b47ee8d6047']"

   strings:
      $hex_string = { 433b3b3d3f312d493a2b24543a2b26653d2f2d7d3c2f2b94392722a5443f41bc5b6d7ed8546ca2ea6188c7f66289c6f8638bc7f8494a5ae338251fc038292695 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
