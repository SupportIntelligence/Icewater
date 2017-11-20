
rule k3e9_15eb149bda2303b2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.15eb149bda2303b2"
     cluster="k3e9.15eb149bda2303b2"
     cluster_size="49"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171117"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre kryptik malicious"
     md5_hashes="['087e561fb6d18af96d1d1c68d0f0d5fd','09e8592536017880ce12c682706d57b7','a2484190ecb3b51e406dcf3ec166f5d8']"

   strings:
      $hex_string = { 006162636465666768696a6b6c6d6e6f707172737475767778797a4142434445464748494a4b4c4d4e4f505152535455565758595a303132333435363738395f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
