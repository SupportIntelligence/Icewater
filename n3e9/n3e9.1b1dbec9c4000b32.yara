
rule n3e9_1b1dbec9c4000b32
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1b1dbec9c4000b32"
     cluster="n3e9.1b1dbec9c4000b32"
     cluster_size="747"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod viking"
     md5_hashes="['01fe2214dba1cffd032bf796653f44c3','02441f6780caa536d336f3a24157d7aa','0d4076e112df666ec9f3d4a837bda06a']"

   strings:
      $hex_string = { ff01555a41df771e43a52a63c207ad992a8abdfe5f12bf2d4693fdecbdcde3ae067d4472b95abcdb1dd9f3c60070eda780747f37abf0a36f59a62d95490b2fba }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
