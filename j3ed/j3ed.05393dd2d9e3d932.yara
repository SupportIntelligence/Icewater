
rule j3ed_05393dd2d9e3d932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3ed.05393dd2d9e3d932"
     cluster="j3ed.05393dd2d9e3d932"
     cluster_size="23"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="malicious proxy ageneric"
     md5_hashes="['0bdde6b788d5d0303d4304c07ccf53a1','1f06e96ec90248337ee1cd11f0065453','c294741ddf73ca61a7dbd08a9c945981']"

   strings:
      $hex_string = { acaa40ab6837804301ffe2514968106810004a03ea83c6084e83c2604203ec2be0526a006a01f7d3424f0013016a38869272c2cb1deac2041a0d910b1fbb5026 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
