
rule k2321_13959250c902f916
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=k2321.13959250c902f916"
     cluster="k2321.13959250c902f916"
     cluster_size="3"
     filetype = "application/gzip"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171124"
     license = "RIL-1.0 [Rick's Internet License] "
     family="regrun ludbaruma rontokbro"
     md5_hashes="['54c28d5b105a544bfeb2446369c6cd1b','7e4a205f8f7ccef964dcaadc2161ca36','987ae409b1869c55a0d326314f24380e']"

   strings:
      $hex_string = { 439e1aa57f6a1263c3317e99e8678a69f4fa2971eab3e2d4e741589fa6f722d9a924a153114860fc3f6647caad28bf92ae96e7ec4439452dbfb73781d58d51cb }

   condition:
      
      filesize > 16384 and filesize < 65536
      and $hex_string
}
