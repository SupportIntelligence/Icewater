
rule n2321_499a92b9caa00b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.499a92b9caa00b12"
     cluster="n2321.499a92b9caa00b12"
     cluster_size="16"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi vjadtre"
     md5_hashes="['01b7bf9d0421dc36640b6758059adf47','42afcdc4f0c8213c1ede4099eddc2318','f95e7f895edebbb06d653bface83404f']"

   strings:
      $hex_string = { 4e4ae3a062cd270728704fd0297c95ee3ac5f381858c83a3db9d15be9e7df27e7a8bc300e7674314b41d91926b20185821bb1b8fc4dce65048bf8d22a8b07bad }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
