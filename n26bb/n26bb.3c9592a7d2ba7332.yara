
rule n26bb_3c9592a7d2ba7332
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.3c9592a7d2ba7332"
     cluster="n26bb.3c9592a7d2ba7332"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="autoit malicious fuerboos"
     md5_hashes="['2bed58b3ab4c7d6bd0aacb493225390cfdc98f53','b83c212a8ab3d090dc4d25832f477319c1a24480','f9b5c36f80fa9620a2e305b2414879071842cb0c']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.3c9592a7d2ba7332"

   strings:
      $hex_string = { f8bf60514b0033f6b0050fb6d83bd37513528bd7e83c7ff9ff5985c0741c8b55fc8b4df88a86014e4b004703fb4684c075d883c8ff5f5e5bc9c38bc6ebf75356 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
