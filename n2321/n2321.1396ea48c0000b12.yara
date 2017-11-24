
rule n2321_1396ea48c0000b12
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=n2321.1396ea48c0000b12"
     cluster="n2321.1396ea48c0000b12"
     cluster_size="82"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171120"
     license = "RIL-1.0 [Rick's Internet License] "
     family="jadtre qvod viking"
     md5_hashes="['08773b83557e993095c7b6c4ba1b6a9a','0aa7be1e9e8cdca04434ba946bdfe0b6','3621a2dfbab81ab666d680eb8b0c652c']"

   strings:
      $hex_string = { 5edee6b083f159877598ca58c72b979427850ce854f8c2bb6de1e017a33e162ccfd4d6ba959e6eed5cb50ac40bc14b3af3dba96c796884b1072df90d8d103cda }

   condition:
      
      filesize > 262144 and filesize < 1048576
      and $hex_string
}
