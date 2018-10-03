
rule n26bb_4db4a692d892f916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.4db4a692d892f916"
     cluster="n26bb.4db4a692d892f916"
     cluster_size="6"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="ursu malicious muldrop"
     md5_hashes="['60c4990e40eb94bdef6c77b20ee28f9d83d94451','8afeb7b5b748bdd7b545cdacaff8fa20eeaed165','ab8150573e60763e18b3385007514ffb07716bac']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.4db4a692d892f916"

   strings:
      $hex_string = { 5c24088a1b4a88194185d277f203c78946105bc20400b85f1c4500e8cb81030083ec2453568bd98b730c578965f085f6750433ffeb0d8b43142bc66a1c9959f7 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
