
rule m3e9_591ce654ce9b0932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.591ce654ce9b0932"
     cluster="m3e9.591ce654ce9b0932"
     cluster_size="55"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171119"
     license = "RIL-1.0 [Rick's Internet License] "
     family="symmi vobfus wbna"
     md5_hashes="['1012ed87f90b60f226a3c759a8f7cde1','174170fe8e7e6b5c5e3d725e14939b3e','9cda95f1d6614975bcf2f950c01da777']"

   strings:
      $hex_string = { 02e877d5feff83c40c8d45b0508d45c0506a02e801d6feff83c40cc3c38b45dc8b4de064890d000000005f5e5bc9c20400e8ddd5feff558bec83ec1868364440 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
