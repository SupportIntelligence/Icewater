
rule n3ef_42549099ea210b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ef.42549099ea210b14"
     cluster="n3ef.42549099ea210b14"
     cluster_size="323"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="browsefox yontoo browse"
     md5_hashes="['011114b08b7f0717338b4f909f0ade5a','02067211edc8d2c4964e570e458bbee3','110c0e71b31d868aa01164b8de3d4462']"

   strings:
      $hex_string = { 316138343765363839353331616439316461626361004f4b00496e7465726e616c005065726d0041626f72740042757379004c6f636b6564004e6f4d656d0052 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
