
rule n3f7_699c92b9c8800b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f7.699c92b9c8800b12"
     cluster="n3f7.699c92b9c8800b12"
     cluster_size="167"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="faceliker clicker html"
     md5_hashes="['02946aab1fd3d45bf46b071ff88ff016','056377dcbe7fdc1179728829ba8094d3','215f3a1e12cee4f94c15a52b0341bbac']"

   strings:
      $hex_string = { 273a20274c6f6164696e675c78323668656c6c69703b277d2c2027646973706c61794d6f646546756c6c2729293b0a5f5769646765744d616e616765722e5f52 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
