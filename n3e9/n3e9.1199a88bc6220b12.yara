
rule n3e9_1199a88bc6220b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.1199a88bc6220b12"
     cluster="n3e9.1199a88bc6220b12"
     cluster_size="30"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171111"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious cerber highconfidence"
     md5_hashes="['00400f698be6d781d4e83f938e7bc81c','09945d240e4f2a2f2cb88484015f15b6','8a3e8d68bf9fa5c24086e0b68f546b26']"

   strings:
      $hex_string = { d53af06437c2e0fe6aeb6f8759aa24a82c8aff4f36db10ce049a831c016616b27bae8e380fd20396651adafc9ce48c12c97e7f79be861314f49ef87384e66b19 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
