
rule n3f7_4a3cea48c0000912
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3f7.4a3cea48c0000912"
     cluster="n3f7.4a3cea48c0000912"
     cluster_size="39"
     filetype = "text/html"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171122"
     license = "RIL-1.0 [Rick's Internet License] "
     family="ramnit html script"
     md5_hashes="['0468fd97b9469f26f7ef7ce899350fc7','0c1a9ff31fa4335488a98ce6cc702368','a5c95266a161f77b299bb39ec6a2ad4f']"

   strings:
      $hex_string = { 31383233374446333432434631354236333741353638414639394230463444454335393142444132383030444632433546364543453933454241354438433430 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
