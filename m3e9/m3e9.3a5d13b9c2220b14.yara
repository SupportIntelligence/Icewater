
rule m3e9_3a5d13b9c2220b14
{

   meta:
     copyright="Copyright (c) 2014-2018 Support Intelligence Inc, All Rights Reserved."
     engine="saphire/1.3.1 divinorum/0.998 icewater/0.4"
     viz_url="http://icewater.io/en/cluster/query?h64=m3e9.3a5d13b9c2220b14"
     cluster="m3e9.3a5d13b9c2220b14"
     cluster_size="39"
     filetype = "PE32 executable (GUI) Intel 80386"
     tlp = "amber"
     version = "icewater snowflake"
     author = "Rick Wesson (@wessorh) rick@support-intelligence.com"
     date = "20171118"
     license = "RIL-1.0 [Rick's Internet License] "
     family="otwycal wapomi viking"
     md5_hashes="['1d274201534dacb23e96946e679f230b','2244f6253261943c946b14001ad62d06','b0171b482f749dba4803ade9c3fc6ba0']"

   strings:
      $hex_string = { 93e7345a90afbe3ebf9bc58b42ea46bd74f6756557947e13642aa3608ffee42480250beee806fc5f3da4dd08899873d650a7d15655fa01f9835cb21e952d36b6 }

   condition:
      
      filesize > 65536 and filesize < 262144
      and $hex_string
}
