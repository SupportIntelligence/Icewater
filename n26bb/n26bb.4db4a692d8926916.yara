
rule n26bb_4db4a692d8926916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.8 divinorum/0.9992 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n26bb.4db4a692d8926916"
     cluster="n26bb.4db4a692d8926916"
     cluster_size="4"
     filetype = ""
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20180911"
     license = "RIL-1.0 [Rick's Internet License]"
     family="ursu malicious muldrop"
     md5_hashes="['eff8cee56171ad1129d89b2c28a4aee1f7595baf','a7c666c8c044060fd2f62a5e2782610fe52dce02','831e9b6e3cdee1ca96839a6e7af1ef27048a0f60']"
     cluster_members="http://icewater.io/en/cluster/detail?h64=n26bb.4db4a692d8926916"

   strings:
      $hex_string = { 5c24088a1b4a88194185d277f203c78946105bc20400b85f1c4500e8cb81030083ec2453568bd98b730c578965f085f6750433ffeb0d8b43142bc66a1c9959f7 }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
