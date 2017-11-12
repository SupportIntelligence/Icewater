
rule n3ec_11b24a6b48800112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n3ec.11b24a6b48800112"
     cluster="n3ec.11b24a6b48800112"
     cluster_size="232"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['01a28b741a9410a2398261cac07f0f76','037672a784f1de90c284b30adcda2b93','16dd5a01b53953a9af917bfa38b1ece4']"

   strings:
      $hex_string = { 006f0020006a0075007300740020006f007500740070007500740020007400680065000d000a00630075007200720065006e0074002000740069006d0065002c }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
