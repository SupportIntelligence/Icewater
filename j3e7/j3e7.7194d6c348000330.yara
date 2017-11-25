
rule j3e7_7194d6c348000330
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3e7.7194d6c348000330"
     cluster="j3e7.7194d6c348000330"
     cluster_size="774"
     filetype = "application/octet-stream"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="shedun androidos risktool"
     md5_hashes="['000185e407296a9ef445aa1963b72c61','0032e04a9a130966d4d7796861b655fe','049f95fb1c8a6dda8523f8dff09b5369']"

   strings:
      $hex_string = { 63742f4669656c643b001a4c6a6176612f6c616e672f7265666c6563742f4d6574686f643b00154c6a6176612f7574696c2f41727261794c6973743b00164c6a }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
