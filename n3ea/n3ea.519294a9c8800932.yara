
rule n3ea_519294a9c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ea.519294a9c8800932"
     cluster="n3ea.519294a9c8800932"
     cluster_size="6459"
     filetype = "application/java-archive"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos dldr andr"
     md5_hashes="['0001de1f92cd2368e013c76e328a9a0d','002189a57904ee073986280d1cebc84b','0094129ad51d1057291e07927b54a098']"

   strings:
      $hex_string = { bb275e7df5d54befbefbee10268760e43159651bc4d106b5348bcc792a030cdf05d8e61cfac8e5722b00ec9e0e6846f8b49c16dd903c0892c781d40a88f6a0a6 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
