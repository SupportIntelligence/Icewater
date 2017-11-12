
rule n3ec_299cea48c0000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ec.299cea48c0000b32"
     cluster="n3ec.299cea48c0000b32"
     cluster_size="2378"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="hacktool autokms kmsauto"
     md5_hashes="['001c9804d38a8091d284f21c9f77ae88','0020a71a003762eca76099e631906823','02a124e630db66b695000c98e571ec3e']"

   strings:
      $hex_string = { ff7c6423b55b83d714ecaae1578492dc6968a95f96fd0a3f5624fe44c7cc589a59f452b6cfeda37ba08a5d046bef6e43ca3d2cb7650b79fc6c768b3b7af3031a }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
