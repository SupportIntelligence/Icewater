
rule k3e9_42949599ee64a447
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.42949599ee64a447"
     cluster="k3e9.42949599ee64a447"
     cluster_size="23"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="virut virtob virux"
     md5_hashes="['947853df4dd7e11fd4b5d581d18586dd','a2ee1bf0055ddcfa8912a865778bf6c7','df67ec3fd0b876791f3597d9e75f78c1']"

   strings:
      $hex_string = { 2c0c4f9da2174311acc3278ce9318c3a98a54890166fe5d667a950269128ce849ea745937e67bb18691493abdff788a73e3a4caefbc4e8106173aa68e682515e }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
