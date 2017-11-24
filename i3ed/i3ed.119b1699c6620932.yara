
rule i3ed_119b1699c6620932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=i3ed.119b1699c6620932"
     cluster="i3ed.119b1699c6620932"
     cluster_size="4"
     filetype = "PE32 executable (DLL) (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="padodor backdoor symmi"
     md5_hashes="['5f4d6d0085c284964f5a2f6fe28e3952','86744266a07905c2aeb494e806d418da','c5f0f7a0127420807cbf46022cfaf915']"

   strings:
      $hex_string = { 7d010dcb432a42f1fef3a5b289b56821eed52d7c6c5878c24d2c5c1345e88405dd69af12057507d19d20c0090a74e11499c6adffd59740dc55ac416bfb8579d6 }

   condition:
      
      filesize > 1024 and filesize < 4096
      and $hex_string
}
