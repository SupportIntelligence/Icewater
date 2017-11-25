
rule k3e9_099cf3e9c8000932
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k3e9.099cf3e9c8000932"
     cluster="k3e9.099cf3e9c8000932"
     cluster_size="6"
     filetype = "application/x-dosexec"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="razy backdoor simbot"
     md5_hashes="['b0b6270c5a553f354e54e4e73d6f70ba','c2aae5f106074b531838b829f2f94ff7','effba014ca64250b1b3286fed6b1e147']"

   strings:
      $hex_string = { 47018a46028847028b45085e5fc9c3908d7431fc8d7c39fcf7c7030000007524c1e90283e20383f908720dfdf3a5fcff2495306840008bfff7d9ff248de06740 }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
