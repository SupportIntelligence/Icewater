
rule k3f7_3314514ad90af916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3f7.3314514ad90af916"
     cluster="k3f7.3314514ad90af916"
     cluster_size="9"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="script faceliker clicker"
     md5_hashes="['41c0d3c49d78ed91ae4b9625e6ef3d99','478ad567bbf94afdd5b0a14f0fd8ac84','e2077877bd63b62a6969611c66e06580']"

   strings:
      $hex_string = { 456c656d656e7442794964282748544d4c3127292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769646765744d616e616765722e5f52 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
