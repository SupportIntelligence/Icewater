
rule m3e9_316339779cbb1112
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.316339779cbb1112"
     cluster="m3e9.316339779cbb1112"
     cluster_size="290"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171109"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi viking"
     md5_hashes="['00872f61ac55ae77d0344994f5793264','0b6c332a5ecf4f7c5eda9fe47dcaa145','3aa5ecb95c4257fec03237887d18f5fb']"

   strings:
      $hex_string = { 7c1b3cda96745eebb100ed9530713d9e18bfa44b387b026d4e48f2754e405b211e4cb90bbcd7e2513af88fc4cd62f052e732529f1ebb1a294cd509cd63d5fd67 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
