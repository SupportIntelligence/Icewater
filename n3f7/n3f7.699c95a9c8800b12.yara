
rule n3f7_699c95a9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f7.699c95a9c8800b12"
     cluster="n3f7.699c95a9c8800b12"
     cluster_size="16"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker script"
     md5_hashes="['0610c9e8f27dcc664771106ac850b6d8','083d7d1c2fbef0edeabf2a0119ea6594','e05acf9feb2e77e14a279c32a5ae9f58']"

   strings:
      $hex_string = { 273a20274c6f6164696e675c78323668656c6c69703b277d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769646765744d616e616765722e5f52 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
