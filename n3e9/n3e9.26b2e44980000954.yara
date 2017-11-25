
rule n3e9_26b2e44980000954
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3e9.26b2e44980000954"
     cluster="n3e9.26b2e44980000954"
     cluster_size="175"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171123"
     license = "RIL-1.0 [Rick's Internet License] "
     family="allaple virut rahack"
     md5_hashes="['016b82d7ddf11289c5adfa2aec5d2dff','0e050a46defafffe52cbff79d57cf547','318e57a301b7f82f77f1410e9de6217b']"

   strings:
      $hex_string = { 70e58d414da86cd51fee5718b788db136bb58c30d6464b80657495e44475ab319e2af3b051724cc93aac6940b2c34af19366995c075e7610e11e977327da6747 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
