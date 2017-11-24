
rule m231b_4bb9005a9ee30912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m231b.4bb9005a9ee30912"
     cluster="m231b.4bb9005a9ee30912"
     cluster_size="4"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="clicker faceliker html"
     md5_hashes="['3cfc3e48ccaf34dec0714323c91b6b09','409f2c22056f44c50ad6e0d138864cf0','ddff7a9700f71066a90434618812b74c']"

   strings:
      $hex_string = { 456c656d656e7442794964282748544d4c3527292c207b7d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769646765744d616e616765722e5f52 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
