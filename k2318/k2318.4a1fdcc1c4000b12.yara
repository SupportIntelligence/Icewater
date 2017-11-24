
rule k2318_4a1fdcc1c4000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2318.4a1fdcc1c4000b12"
     cluster="k2318.4a1fdcc1c4000b12"
     cluster_size="78"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="likejack faceliker clicker"
     md5_hashes="['041762bb2713b110c67605a989a76f06','04210d3aedf7786fba073dad9eb66551','37465cd609e82f0decdc8251637eeb2d']"

   strings:
      $hex_string = { 222c31303030293b0a7d20293b0a66756e6374696f6e20636c69636b6a61636b5f686964657228297b0a6a51756572792822696e70757422292e6d6f7573656f }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
