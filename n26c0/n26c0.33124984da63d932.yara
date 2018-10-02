
rule n26c0_33124984da63d932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26c0.33124984da63d932"
     cluster="n26c0.33124984da63d932"
     cluster_size="3"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="malicious kryptik prepscram"
     md5_hashes="['9bd58dd766e6dc988df98dcf48ead123fe7ef9b4','12b9d2a62738e224e3085e02e8d7e767ceade1d8','644f7e4bdc2c094ad038a0582f1cca437b2a4b2f']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26c0.33124984da63d932"

   strings:
      $hex_string = { 8d46185750e895c3ffff895e0483c40c33db89be1c02000043395de87651807dee008d45ee74218a480184c9741a0fb6d10fb608eb06804c0e1904413bca76f6 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
