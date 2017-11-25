
rule n3ed_054b35e9c8800916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ed.054b35e9c8800916"
     cluster="n3ed.054b35e9c8800916"
     cluster_size="3"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="floxif pioneer malicious"
     md5_hashes="['32e050729fa2458b017799f777414b90','d40695fe06856fc5ce90a7279a36d00d','d5c9e0d43fd307224008fd0c739988de']"

   strings:
      $hex_string = { 0f8327612f39be4c4fcba7d6e4c40847d3c2e3c61c9cb9fc86c86e05597795043ed1114c254678c0dc151ed949f750cf73ec2deef4d9b5d54e8f31a8f5de21db }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
