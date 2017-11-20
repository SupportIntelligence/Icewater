
rule k3e9_3deb149bda2303b2
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.3deb149bda2303b2"
     cluster="k3e9.3deb149bda2303b2"
     cluster_size="10"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="upatre kryptik malicious"
     md5_hashes="['5f51a2a7bf467953cf8796d1268f8442','a57fc431c6fa26798e479b21b7e2ef22','ff30ad009266905a48f01d9958b4b776']"

   strings:
      $hex_string = { 006162636465666768696a6b6c6d6e6f707172737475767778797a4142434445464748494a4b4c4d4e4f505152535455565758595a303132333435363738395f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
