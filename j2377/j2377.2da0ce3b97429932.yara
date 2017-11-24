
rule j2377_2da0ce3b97429932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j2377.2da0ce3b97429932"
     cluster="j2377.2da0ce3b97429932"
     cluster_size="16"
     filetype = "HTML document"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="html twetti iframe"
     md5_hashes="['03f45369d926b8fadafaf19d361b03fe','08abb8d88cab2a604364603e4c1d651d','eed9fa1ec901cd3bc3b8dc9f3e33290e']"

   strings:
      $hex_string = { 3363285a336329392b5a3235313976657e7364795a323537467e3053717c73657c7164755d717779735e657d727562387471695a3363307d5a323537467e6478 }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
