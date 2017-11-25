
rule n3ea_511adce9c8800932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ea.511adce9c8800932"
     cluster="n3ea.511adce9c8800932"
     cluster_size="2353"
     filetype = "application/java-archive"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="androidos dldr andr"
     md5_hashes="['002c8b7e1ae2a77dc3ac0bfdd71c5db4','003f14787e850a3e966206dd8b5626cf','017d8903a8f389f108b64a7dc90ed1ad']"

   strings:
      $hex_string = { bb275e7df5d54befbefbee10268760e43159651bc4d106b5348bcc792a030cdf05d8e61cfac8e5722b00ec9e0e6846f8b49c16dd903c0892c781d40a88f6a0a6 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
