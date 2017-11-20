
rule k3e9_4563c22679b34cb7
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.4563c22679b34cb7"
     cluster="k3e9.4563c22679b34cb7"
     cluster_size="5"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['b99be3aed35be270219e60c11fe5be0d','baec9416c00eed967679c3dd72675751','e4e72be5865fc994972c7100a779d707']"

   strings:
      $hex_string = { 433b3b3d3f312d493a2b24543a2b26653d2f2d7d3c2f2b94392722a5443f41bc5b6d7ed8546ca2ea6188c7f66289c6f8638bc7f8494a5ae338251fc038292695 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
