
rule j3f8_50623116da630110
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=j3f8.50623116da630110"
     cluster="j3f8.50623116da630110"
     cluster_size="29"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180910"
     license = "RIL-1.0 [Rick's Internet License]"
     family="lockscreen locker androidos"
     md5_hashes="['86b2214b1aef9ac92aa3220e4424f55278f8adc6','6caeeb15bcd943ca8bd267219097cd37a01aa530','82294b97270547e077951bc4ea2bbdd7a494fdee']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=j3f8.50623116da630110"

   strings:
      $hex_string = { 057f6e20180076000c061f0617000762072622071f00077d07d707d8070970202c0098006e201c00760022061500076d07d607d712e812e9130ad207121b12dc }

   condition:
      
      filesize > 4096 and filesize < 16384
      and $hex_string
}
